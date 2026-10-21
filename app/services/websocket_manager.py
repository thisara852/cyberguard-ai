import json
from typing import List
from fastapi import WebSocket

class WebSocketConnectionManager:
    """Manages active WebSocket connections for live SOC dashboard streaming (FR-20)."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message_dict: dict):
        """Broadcast JSON message to all connected SOC clients."""
        payload = json.dumps(message_dict, default=str)
        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload)
            except Exception:
                self.disconnect(connection)

ws_manager = WebSocketConnectionManager()
