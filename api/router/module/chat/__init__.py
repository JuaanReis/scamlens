import asyncio
from datetime import datetime, timezone
from urllib.parse import urlsplit
from fastapi import (
    APIRouter, Depends, HTTPException, Query,
    WebSocket, WebSocketDisconnect,
)
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from api.middleware.auth import get_current_user
from providers.database.chat_messages import add_message, get_recent_messages
from scamLens import config

from api.middleware.limiter import RateLimitedRoute

router = APIRouter(route_class=RateLimitedRoute, prefix="/api/chat", tags=["chat"])
chat_config = config["chat"]

class MessageIn(BaseModel):
    content: str = Field(min_length=1, max_length=chat_config["max_message_length"])
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
                await run_in_threadpool(get_current_user, ws)
                await asyncio.wait_for(ws.send_json(data), timeout=2.0)
            except Exception:
                await self.close(ws)

    async def close(self, ws):
        self.disconnect(ws)
        try:
            await asyncio.wait_for(ws.close(code=1008), timeout=2.0)
        except Exception:
            pass

manager = ConnectionManager()

def _origin(value):
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
            return None
        port = parsed.port
        return parsed.scheme, parsed.hostname.lower(), port if port is not None else (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None

def _origin_allowed(ws):
    supplied = ws.headers.get("origin")
    if supplied is None:
        return True
    origin = _origin(supplied)
    scheme = "https" if ws.url.scheme == "wss" else "http"
    same_origin = _origin(f"{scheme}://{ws.url.netloc}")
    allowed = [_origin(value) for value in config["cors"]["allow_origins"] if value != "*"]
    return origin is not None and (origin == same_origin or origin in allowed)

def _to_utc_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

@router.get("/messages")
def list_messages(
    limit: int = Query(chat_config["default_page_size"], ge=1, le=chat_config["max_page_size"]),
    before_id: int | None = Query(None, ge=1),
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
    if not _origin_allowed(ws):
        await ws.close(code=1008)
        return
    try:
        await run_in_threadpool(get_current_user, ws)
    except HTTPException:
        await ws.close(code=1008)
        return
    await manager.connect(ws)
    try:
        while True:
            remaining = ws.state.token_expires_at - datetime.now(timezone.utc).timestamp()
            if remaining <= 0:
                await manager.close(ws)
                break
            try:
                await asyncio.wait_for(ws.receive_text(), timeout=min(remaining, 5.0))
            except asyncio.TimeoutError:
                pass
            try:
                await run_in_threadpool(get_current_user, ws)
            except HTTPException:
                await manager.close(ws)
                break
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(ws)
