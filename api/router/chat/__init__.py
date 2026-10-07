from datetime import datetime, timezone
from fastapi import (
    APIRouter, Depends, HTTPException, Query,
    WebSocket, WebSocketDisconnect,
)
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from api.middleware.auth import get_current_user
from providers.database.chat_messages import add_message, get_recent_messages

router = APIRouter(prefix="/api/chat", tags=["chat"])

class MessageIn(BaseModel):
    content: str = Field(min_length=1, max_length=2000)
    sent_at: datetime

class ConnectionManager:
    def __init__(self):
        self.connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.connections:
            self.connections.remove(ws)

    async def broadcast(self, data: dict):
        for ws in list(self.connections):
            try:
                await ws.send_json(data)
            except Exception:
                self.disconnect(ws)

manager = ConnectionManager()

def _to_utc_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

@router.get("/messages")
def list_messages(
    limit: int = Query(50, ge=1, le=100),
    before_id: int | None = None,
    user: dict = Depends(get_current_user),
):
    return get_recent_messages(limit, before_id)

@router.post("/messages", status_code=201)
async def send_message(body: MessageIn, user: dict = Depends(get_current_user)):
    content = body.content.strip()
    if not content:
        raise HTTPException(status_code=422, detail="Message cannot be empty.")

    sent_at = _to_utc_iso(body.sent_at)
    message_id = await run_in_threadpool(add_message, user["id"], content, sent_at)

    payload = {
        "id": message_id,
        "name": user["name"],
        "avatar_url": user["avatar_url"],
        "content": content,
        "sent_at": sent_at,
    }
    await manager.broadcast({"type": "message", **payload})
    return payload

@router.websocket("/ws")
async def chat_ws(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(ws)