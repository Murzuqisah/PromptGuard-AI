"""WebSocket event streaming.

Manages connected WebSocket clients and broadcasts scan events in real-time.
Clients connect to /ws/events and receive JSON messages for every scan event.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

_connections: list[WebSocket] = []


async def connect(websocket: WebSocket) -> None:
    await websocket.accept()
    _connections.append(websocket)
    logger.info(f"WebSocket client connected ({len(_connections)} total)")


def disconnect(websocket: WebSocket) -> None:
    if websocket in _connections:
        _connections.remove(websocket)
    logger.info(f"WebSocket client disconnected ({len(_connections)} total)")


async def broadcast(event: dict[str, Any]) -> None:
    """Broadcast an event to all connected WebSocket clients."""
    if not _connections:
        return
    message = json.dumps(event, default=str)
    disconnected: list[WebSocket] = []
    for ws in _connections:
        try:
            await ws.send_text(message)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        disconnect(ws)


def get_connection_count() -> int:
    return len(_connections)
